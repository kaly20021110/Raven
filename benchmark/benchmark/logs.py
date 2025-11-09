from datetime import datetime
from glob import glob
from multiprocessing import Pool
from os.path import join
from re import findall, search
from statistics import mean
import matplotlib.pyplot as plt
from collections import defaultdict

from benchmark.utils import Print


class ParseError(Exception):
    pass


class LogParser:
    def __init__(self,nodes, faults, protocol, ddos):

        assert all(isinstance(x, str) for x in nodes)

        self.protocol = protocol
        self.ddos = ddos
        self.faults = faults
        self.committee_size = len(nodes)

        # Parse the nodes logs.
        try:
            with Pool() as p:
                results = p.map(self._parse_nodes, nodes)
        except (ValueError, IndexError) as e:
            raise ParseError(f'Failed to parse node logs: {e}')
        nocounts,epochcounts,batchs,proposals, commits,proposalcommits,configs,max_faba_invoke,real_faba_invoke,commit_round = zip(*results)
        self.nocounts=self._merge_results([x.items() for x in nocounts])
        self.epochcounts=self._merge_results([x.items() for x in epochcounts])
        self.proposals = self._merge_results([x.items() for x in proposals])
        self.proposalcommits = self._merge_results([x.items() for x in proposalcommits])
        self.commits = self._merge_results([x.items() for x in commits])
        self.batchs = self._merge_results([x.items() for x in batchs])
        self.configs = configs[0]
        self.max_faba_invoke=self._merge_aba_results(max_faba_invoke)
        self.real_faba_invoke=self._merge_aba_results(real_faba_invoke)
        self.commit_round = self._merge_commit_rounds_results(commit_round)
        
              


    def _merge_results(self, input):
        # Keep the earliest timestamp.
        merged = {}
        for x in input:
            for k, v in x:
                if not k in merged or v < merged[k]:
                    merged[k] = v
        return merged
    
    def _merge_aba_results(self, input):
        merged = {}
        for x in input:
            if isinstance(x, dict):
                for epoch, count in x.items():
                    if epoch not in merged or count > merged.get(epoch, 0):
                        merged[epoch] = count
        return merged
    
    def _merge_commit_rounds_results(self, input):
        # 修复合并逻辑
        merged = {}
        for x in input:
            if isinstance(x, dict):
                for epoch, count in x.items():
                    if epoch not in merged or count < merged.get(epoch, 0):
                        merged[epoch] = count
        return merged

    def _parse_nodes(self, log):
        if search(r'panic', log) is not None:
            raise ParseError('Client(s) panicked')

        tmp = findall(r'\[INFO] (.*) core.* can not commit any blocks in this epoch (\d+)', log)
        nocounts = { id:self._to_posix(t) for t,id in tmp }
        
        tmp = findall(r'\[INFO] (.*) core.* advance next epoch (\d+)', log)
        epochcounts = { id:self._to_posix(t) for t,id in tmp}
        
        tmp = findall(r'\[INFO] (.*) pool.* Received Batch (\d+)', log)
        batchs = { id:self._to_posix(t) for t,id in tmp}
        
        tmp = findall(r'\[INFO] (.*) core.* create ConsensusBlock (epoch \d+ node \d+)', log)
        tmp = { (id,self._to_posix(t)) for t,id in tmp }
        proposals = self._merge_results([tmp])
        
        tmp = findall(r'\[INFO] (.*) commitor.* commit ConsensusBlock (epoch \d+ node \d+)', log)
        tmp = {(id, self._to_posix(t)) for t, id in tmp}
        proposalcommits = self._merge_results([tmp])

        tmp = findall(r'\[INFO] (.*) commitor.* commit Block node \d+ batch_id (\d+)', log)
        tmp = {(id, self._to_posix(t)) for t, id in tmp}
        commits = self._merge_results([tmp])
        
        tmp = findall(r'In Epoch (\d+),the MAX FABA invoke counts is (\d+)', log)
        max_faba_counts = {int(epoch): int(count) for epoch, count in tmp}
        # max_faba_counts = self._merge_aba_results([tmp])
        
        tmp = findall(r'In Epoch (\d+),the invoke count of FABA is (\d+)', log)
        real_faba_counts = {int(epoch): int(count) for epoch, count in tmp}
        # real_faba_counts = self._merge_aba_results([tmp])
        
        tmp = findall(r'In Epoch (\d+),the block commit at the (\d+) round', log)
        commit_round={int(epoch): int(round) for epoch, round in tmp}
        

            

        configs = {
            'consensus': {
                'faults': int(
                    search(r'Consensus DDos: .*, Faults: (\d+)', log).group(1)
                ),
            },
            'pool': {
                'tx_size': int(
                    search(r'Transaction pool tx size set to (\d+)', log).group(1)
                ),
                'batch_size': int(
                    search(r'Transaction pool batch size set to (\d+)', log).group(1)
                ),
                'rate':int(
                    search(r'Transaction pool tx rate set to (\d+)', log).group(1)
                ),
            }
        }

        return nocounts,epochcounts,batchs,proposals, commits,proposalcommits,configs,max_faba_counts,real_faba_counts,commit_round

    def _to_posix(self, string):
        # 解析时间字符串为 datetime 对象
        dt = datetime.strptime(string, "%Y/%m/%d %H:%M:%S.%f")
        # 转换为 Unix 时间戳
        timestamp = dt.timestamp()
        return timestamp    

    def _consensus_throughput(self):
        if not self.commits:
            return 0, 0
        start, end = min(self.proposals.values()), max(self.proposalcommits.values())
        duration = end - start
        tps = len(self.commits)*self.configs['pool']['batch_size'] / duration
        return tps, duration

    def _consensus_latency(self):
        latency = [c - self.proposals[d] for d, c in self.proposalcommits.items() if d in self.proposals]
        return mean(latency) if latency else 0

    def _end_to_end_throughput(self):
        if not self.commits:
            return 0, 0
        start, end = min(self.batchs.values()), max(self.commits.values())
        duration = end - start
        tps = len(self.commits)*self.configs['pool']['batch_size'] / duration
        return tps, duration

    def _end_to_end_latency(self):
        latency = []
        for id,t in self.commits.items():
            if id in self.batchs:
                latency += [t-self.batchs[id]]
        return mean(latency) if latency else 0
    
    #对于faba的调用的测试
    def _faba_analyze(self):
        # print(f"Debug - max_faba_invoke: {self.max_faba_invoke}")
        # print(f"Debug - real_faba_invoke: {self.real_faba_invoke}")
        max_allfaba_count=0
        
        for epoch,count in self.max_faba_invoke.items():
            max_allfaba_count+=count
        
        real_allfaba_count=0
        for epoch,count in self.real_faba_invoke.items():
            real_allfaba_count+=count
            
        max_count_distribution = {}
        real_count_distribution = {}
        for epoch, count in self.max_faba_invoke.items():
            if count not in max_count_distribution:
                max_count_distribution[count] = 0
            max_count_distribution[count] += 1
        for epoch, count in self.real_faba_invoke.items():
            if count not in real_count_distribution:
                real_count_distribution[count] = 0
            real_count_distribution[count] += 1
        return {
            'max_total': max_allfaba_count,
            'real_total': real_allfaba_count,
            'max_distribution': max_count_distribution,
            'real_distribution': real_count_distribution
        }
    
    def commitrounds_analyze(self):
        commit_rounds_distribution = {}
        for epoch, count in self.commit_round.items():
            if count not in commit_rounds_distribution:
                commit_rounds_distribution[count] = 0
            commit_rounds_distribution[count] += 1
        return {
            'commit_rounds_distribution': commit_rounds_distribution
        }      

    def result(self):        
        consensus_latency = self._consensus_latency() * 1000
        consensus_tps, _ = self._consensus_throughput()
        end_to_end_tps, duration = self._end_to_end_throughput()
        end_to_end_latency = self._end_to_end_latency() * 1000
        nocounts = len(self.nocounts)
        commitcount=len(self.commits)
        epochcounts=len(self.epochcounts)
        tx_size = self.configs['pool']['tx_size']
        batch_size = self.configs['pool']['batch_size']
        rate = self.configs['pool']['rate']
        faba_analyze=self._faba_analyze()
        commit_rounds=self.commitrounds_analyze()
        # 构建faba分析结果的字符串
        faba_result_str = "FABA分析结果:\n"
        faba_result_str += f"  MAX FABA总调用次数: {faba_analyze['max_total']:,}\n"
        faba_result_str += f"  REAL FABA总调用次数: {faba_analyze['real_total']:,}\n"
        
        faba_result_str += "  MAX FABA分布:\n"
        for count, epoch_count in sorted(faba_analyze['max_distribution'].items()):
            faba_result_str += f"    count={count}: {epoch_count}个epoch\n"
        
        faba_result_str += "  REAL FABA分布:\n"
        for count, epoch_count in sorted(faba_analyze['real_distribution'].items()):
            faba_result_str += f"    count={count}: {epoch_count}个epoch\n"   
            
        #构建commit轮次分析结果的字符串
        commit_rounds_str=   "Commit轮次分析结果:\n"
        for count, epoch_count in sorted(commit_rounds['commit_rounds_distribution'].items()):
            commit_rounds_str += f"    count={count}: {epoch_count}个epoch\n"  
        
        return (
            '\n'
            '-----------------------------------------\n'
            ' SUMMARY:\n'
            '-----------------------------------------\n'
            ' + CONFIG:\n'
            f' Protocol: {self.protocol} \n'
            f' DDOS attack: {self.ddos} \n'
            f' Committee size: {self.committee_size} nodes\n'
            f' Input rate: {rate:,} tx/s\n'
            f' Transaction size: {tx_size:,} B\n'
            f' Batch size: {batch_size:,} tx/Batch\n'
            f' Faults: {self.faults} nodes\n'
            f' Execution time: {round(duration):,} s\n'
            '\n'
            ' + RESULTS:\n'
            f' Consensus TPS: {round(consensus_tps):,} tx/s\n'
            f' Consensus latency: {round(consensus_latency):,} ms\n'
            '\n'
            f' End-to-end TPS: {round(end_to_end_tps):,} tx/s\n'
            f' End-to-end latency: {round(end_to_end_latency):,} ms\n'
            f' The epoch count can not commit block: {round(nocounts):,}\n'
            f' The all epoch counts : {round(epochcounts):,}\n'
            f' The all epoch count commit block: {round(commitcount):,}\n'
             '\n'
            f' {faba_result_str}\n'
             '\n'
            f' {commit_rounds_str}\n'
            '-----------------------------------------\n'
        )
          
        
    def print(self, filename):
        assert isinstance(filename, str)
        with open(filename, 'a') as f:
            f.write(self.result())

    @classmethod
    def process(cls, directory, faults=0, protocol="", ddos=False):
        assert isinstance(directory, str)

        nodes = []
        for filename in sorted(glob(join(directory, 'node-info-*.log'))):
            with open(filename, 'r') as f:
                nodes += [f.read()]

        return cls(nodes, faults=faults, protocol=protocol, ddos=ddos)