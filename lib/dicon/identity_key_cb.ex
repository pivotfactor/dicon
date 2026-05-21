defmodule Dicon.IdentityKeyCb do
  @behaviour :ssh_client_key_api

  def user_key(algorithm, options) do
    case identity_file(options) do
      nil ->
        :ssh_file.user_key(algorithm, options)

      identity_file ->
        with {:ok, pem} <- File.read(identity_file),
             {:ok, [{private_key, _attrs} | _]} <-
               :ssh_file.decode_ssh_file(
                 :private,
                 algorithm,
                 pem,
                 identity_pass_phrase(algorithm, options)
               ) do
          {:ok, private_key}
        else
          {:error, reason} -> {:error, format_error(reason)}
        end
    end
  end

  def is_host_key(key, host, port, algorithm, options) do
    :ssh_file.is_host_key(key, host, port, algorithm, options)
  end

  def add_host_key(host, port, public_key, options) do
    :ssh_file.add_host_key(host, port, public_key, options)
  end

  defp identity_file(options) do
    options
    |> Keyword.get(:key_cb_private, [])
    |> Keyword.get(:identity_file)
  end

  defp identity_pass_phrase(algorithm, options) do
    case pass_phrase_key(algorithm) do
      nil -> :ignore
      key -> Keyword.get(options, key, :ignore)
    end
  end

  defp pass_phrase_key(:"ssh-dss"), do: :dsa_pass_phrase
  defp pass_phrase_key(:"ssh-rsa"), do: :rsa_pass_phrase
  defp pass_phrase_key(:"rsa-sha2-256"), do: :rsa_pass_phrase
  defp pass_phrase_key(:"rsa-sha2-384"), do: :rsa_pass_phrase
  defp pass_phrase_key(:"rsa-sha2-512"), do: :rsa_pass_phrase
  defp pass_phrase_key(:"ecdsa-sha2-nistp256"), do: :ecdsa_pass_phrase
  defp pass_phrase_key(:"ecdsa-sha2-nistp384"), do: :ecdsa_pass_phrase
  defp pass_phrase_key(:"ecdsa-sha2-nistp521"), do: :ecdsa_pass_phrase
  defp pass_phrase_key(_algorithm), do: nil

  defp format_error(reason) when is_binary(reason), do: reason
  defp format_error(reason), do: inspect(reason)
end
