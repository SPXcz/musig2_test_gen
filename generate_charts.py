import matplotlib.pyplot as plt
import pandas as pd
from scipy.stats import pearsonr

SIGN_PERF_IN = "perf_results/sign_perf_test.csv"

def analyze_keygen(path):
    print("===KEYGEN===")
    mean_std(path, ['time'])

def analyze_noncegen(path):
    print("===NONCEGEN===")
    mean_std(path, ['dataLoading', 'noncegen'])

def analyze_sign(path):
    print("===SIGN===")
    mean_std(path, ['time'])

    df_in = pd.read_csv(SIGN_PERF_IN)
    df_in.reset_index(drop=True)
    df_out = pd.read_csv(path)

    skeys = df_in['privateKey'].apply(lambda x: int(x, 16))
    secnonces = df_in['secnonce'].apply(lambda x: int(x, 16))
    df_skeys = pd.concat([df_out, skeys.rename('skeys')], axis=1).sort_values(by=['skeys'])
    df_seconces = pd.concat([df_out, secnonces], axis=1).sort_values(by=['secnonce'])

    # Delete outliers

    # pearson_skey = df_skeys['skeys'].corr(df_skeys['time'])
    # pearson_secnonce = df_seconces['secnonce'].corr(df_seconces['time'])

    _, p_value_skey = pearsonr(to_np_arr(df_skeys['skeys']), to_np_arr(df_skeys['time']))
    _, p_value_secnonce = pearsonr(to_np_arr(df_seconces['secnonce']), to_np_arr(df_seconces['time']))

    print("p_skey=", p_value_skey, "p_secnonce=", p_value_secnonce)

    # Simple plots
    df_skeys.plot(
        title='Dependency of signing time on secret share value', 
        x='skeys',
        y='time',
        xlabel='Secret share value', 
        ylabel='Signing time [ms]')

    df_seconces.plot(
        title='Dependency of signing time on secnonce value', 
        x='secnonce',
        y='time',
        xlabel='Secnonce value', 
        ylabel='Signing time [ms]')

    # Possible timing attack

    df_skeys['hamming_weight'] = df_skeys['skeys'].apply(lambda x: x.bit_count())
    df_seconces['hamming_weight'] = df_seconces['secnonce'].apply(lambda x: x.bit_count())
    df_skeys = df_skeys.sort_values(by=['hamming_weight'])
    df_seconces = df_seconces.sort_values(by=['hamming_weight'])

    # pearson_skey = df_skeys['hamming_weight'].corr(df_skeys['time'])
    # pearson_secnonce = df_seconces['hamming_weight'].corr(df_seconces['time'])
    _, p_value_skey = pearsonr(to_np_arr(df_skeys['hamming_weight']), to_np_arr(df_skeys['time']))
    _, p_value_secnonce = pearsonr(to_np_arr(df_seconces['hamming_weight']), to_np_arr(df_seconces['time']))

    print("p_skey_ham=", p_value_skey, "p_secnonce_ham=", p_value_secnonce)

    df_skeys.plot.scatter(
        title='Dependency of signing time on the hamming weight of the secret share', 
        x='hamming_weight',
        y='time',
        xlabel='Secret share hamming weight', 
        ylabel='Signing time [ms]')

    df_seconces.plot.scatter(
        title='Dependency of signing time on the hamming weight of secnonce', 
        x='hamming_weight',
        y='time',
        xlabel='Secnonce hamming weight', 
        ylabel='Signing time [ms]')

    plt.show() 

def to_np_arr(series: pd.Series):
    return pd.to_numeric(series, errors='coerce').to_numpy()

def mean_std(path: str, columns: list[str]):
    df = pd.read_csv(path)
    for column in columns:
        mean = df[column].mean()
        std = df[column].std()
        print("Column: ", column, "| Mean:", mean, "| Standard deviation:", std)

def main():
    analyze_keygen("perf_results/keygen_perf_result.csv")
    analyze_noncegen("perf_results/noncegen_perf_result.csv")
    analyze_sign("perf_results/sign_perf_result.csv")

if __name__ == "__main__":
    main()