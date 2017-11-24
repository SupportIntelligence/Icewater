
rule o3e9_32b94be2d8bb1916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.32b94be2d8bb1916"
     cluster="o3e9.32b94be2d8bb1916"
     cluster_size="9"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="cosmu mikey malicious"
     md5_hashes="['0470497e5dbb113b37941bdb723bf989','15bc0c3a91aa496c849791c6877a6de8','e61a6288f50965ccef96105fdde2595e']"

   strings:
      $hex_string = { 7ca8a517d04bc701dac6c4bc234a72274cdcadb47a7b9436f4a2e1d66e9193709db2d8a3d29c3fac645ffd81831896576fee6003003acb215866d1bf483da9bd }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
