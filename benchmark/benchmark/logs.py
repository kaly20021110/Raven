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
        nocounts,epochcounts,batchs,proposals, commits,proposalcommits,configs,faba_results,round_stats = zip(*results)
        self.nocounts=self._merge_results([x.items() for x in nocounts])
        self.epochcounts=self._merge_results([x.items() for x in epochcounts])
        self.proposals = self._merge_results([x.items() for x in proposals])
        self.proposalcommits = self._merge_results([x.items() for x in proposalcommits])
        self.commits = self._merge_results([x.items() for x in commits])
        self.batchs = self._merge_results([x.items() for x in batchs])
        self.configs = configs[0]
        
        self.faba_stats=self._process_faba_stats(faba_results)
        self.round_stats=self._process_round_stats(round_stats)
        
    def _process_faba_stats(self, faba_results):
        """合并所有节点的FABA统计结果"""
        merged_stats = defaultdict(dict)
        
        for node_stats in faba_results:
            for epoch, stats in node_stats.items():
                if epoch not in merged_stats:
                    merged_stats[epoch] = stats.copy()
                else:
                    # 如果同一个epoch有多个提交记录，选择调用次数最多的
                    if stats['invokes_before_commit'] > merged_stats[epoch]['invokes_before_commit']:
                        merged_stats[epoch] = stats.copy()
        
        return dict(merged_stats)      
      
    def _process_round_stats(self, round_results):
        """合并所有节点的round统计结果 - 修正：对epoch去重并取最大round"""
        # 首先收集所有epoch的最大round值
        epoch_max_round = defaultdict(int)
        
        for node_round_stats in round_results:
            for epoch, round_num in node_round_stats.items():
                if round_num > epoch_max_round[epoch]:
                    epoch_max_round[epoch] = round_num
        
        # 然后统计每个round有多少个不同的epoch
        round_count = defaultdict(int)
        for epoch, max_round in epoch_max_round.items():
            round_count[max_round] += 1
        
        return dict(round_count)
              


    def _merge_results(self, input):
        # Keep the earliest timestamp.
        merged = {}
        for x in input:
            for k, v in x:
                if not k in merged or v < merged[k]:
                    merged[k] = v
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
        
        #这一部分需要增加对于FABA调用次数的判断
        invokes = findall(r'\[INFO] (.*) core.* In Epoch (\d+),invoke the (\d+) FABA', log)
        faba_commits = findall(r'\[INFO] (.*) core.* IN Epoch (\d+),actually commit the block in the (\d+) FABA', log)
        
        invoke_dict = defaultdict(list)
        for t, epoch_str, index_str in invokes:  # 注意：这里可能有3个元素
            epoch = int(epoch_str)
            index = int(index_str)
            invoke_dict[epoch].append(index)
        
        commit_dict = {}
        for t, epoch_str, index_str in faba_commits:  # 注意：这里可能有3个元素
            epoch = int(epoch_str)
            index = int(index_str)
            commit_dict[epoch] = index
        #计算每个epoch的FABA统计
        faba_stats = {}
        for epoch, commit_index in commit_dict.items():
            invoke_list = invoke_dict.get(epoch, [])
            count_before_commit = len([i for i in invoke_list if i < commit_index])
            
            faba_stats[epoch] = {
                'commit_index': commit_index,
                'invokes_before_commit': count_before_commit,
                'total_invokes': len(invoke_list),
                'invoke_list': sorted(invoke_list)
            }     
            
        #统计每一个epoch需要多少轮才能结束  
        # 修正：解析round提交统计 - 记录每个epoch的最大round
        round_commits = findall(r'\[INFO] .* In Epoch (\d+),the block commit at the (\d+) round', log)
        round_stats = defaultdict(int)  # epoch -> max_round
        
        for epoch_str, round_str in round_commits:
            epoch = int(epoch_str)
            round_num = int(round_str)
            # 对于同一个epoch，记录最大的round值
            if round_num > round_stats[epoch]:
                round_stats[epoch] = round_num

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

        return nocounts,epochcounts,batchs,proposals, commits,proposalcommits,configs,faba_stats,round_stats

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
    
    def _faba_statistics(self):
        """生成FABA统计信息"""
        if not self.faba_stats:
            return "No FABA statistics available\n"
        
        result = "FABA Statistics:\n"
        result += "================\n"
        
        total_invokes_before_commit = 0
        total_commits = len(self.faba_stats)
        
        for epoch, stats in sorted(self.faba_stats.items()):
            result += f"Epoch {epoch}: 在第{stats['commit_index']}个FABA输出结果之前调用了{stats['invokes_before_commit']}个FABA\n"
            total_invokes_before_commit += stats['invokes_before_commit']
        
        if total_commits > 0:
            avg_invokes = total_invokes_before_commit / total_commits
            result += f"\nSummary:\n"
            result += f"Total epochs with FABA commits: {total_commits}\n"
            result += f"Total FABA invoke counts: {total_invokes_before_commit}\n"
            result += f"Average FABA invokes before commit: {avg_invokes:.2f}\n"
        
        return result    
    
    def _round_statistics(self):
        """生成round提交统计信息 - 修正：基于去重后的epoch统计"""
        if not self.round_stats:
            return "No round commit statistics available\n"
        
        result = "Round Commit Statistics:\n"
        result += "========================\n"
        
        total_epochs = sum(self.round_stats.values())
        
        # 按round数排序输出
        for round_num in sorted(self.round_stats.keys()):
            count = self.round_stats[round_num]
            percentage = (count / total_epochs) * 100 if total_epochs > 0 else 0
            result += f"Round {round_num}: {count}个epoch ({percentage:.1f}%)\n"
        
        result += f"\nSummary:\n"
        result += f"Total distinct epochs with commit records: {total_epochs}\n"
        
        if self.round_stats:
            # 计算平均round（加权平均）
            total_rounds = sum(round_num * count for round_num, count in self.round_stats.items())
            avg_round = total_rounds / total_epochs
            max_round = max(self.round_stats.keys())
            min_round = min(self.round_stats.keys())
            
            result += f"Average commit round: {avg_round:.2f}\n"
            result += f"Minimum commit round: {min_round}\n"
            result += f"Maximum commit round: {max_round}\n"
            # 添加分布信息
            result += f"\nDistribution:\n"
            for round_num in sorted(self.round_stats.keys()):
                count = self.round_stats[round_num]
                result += f"  Round {round_num}: {count} epochs\n"
        
        return result
    

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
        
        round_stats = self._round_statistics()
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
            ' + ROUND STATISTICS:\n'
            f'{round_stats}'
            '-----------------------------------------\n'
        )
          
        
    def print(self, filename):
        assert isinstance(filename, str)
        with open(filename, 'a') as f:
            f.write(self.result())
        faba_filename = filename.replace('.log', '_faba_stats.txt')
        with open(faba_filename, 'a') as f:
            f.write(self._faba_statistics())
         # 新增：生成round统计文件
        round_filename = filename.replace('.log', '_round_stats.txt')
        with open(round_filename, 'a') as f:
            f.write(self._round_statistics())

    @classmethod
    def process(cls, directory, faults=0, protocol="", ddos=False):
        assert isinstance(directory, str)

        nodes = []
        for filename in sorted(glob(join(directory, 'node-info-*.log'))):
            with open(filename, 'r') as f:
                nodes += [f.read()]

        return cls(nodes, faults=faults, protocol=protocol, ddos=ddos)