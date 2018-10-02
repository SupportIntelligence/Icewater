
rule k2318_2752ca9adee30b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.2752ca9adee30b12"
     cluster="k2318.2752ca9adee30b12"
     cluster_size="74"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['2d47c6b4c5d24a72eb8eae75e8f76f610e3fa501','b01fb10251c477599a17eda23a1d0d0587b9ecf1','197e4fd8f49c2e6deb6704de72e43c91e5ff1f3e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.2752ca9adee30b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
