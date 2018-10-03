
rule ofc8_699852ecde430b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=ofc8.699852ecde430b12"
     cluster="ofc8.699852ecde430b12"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="riskware smsreg androidos"
     md5_hashes="['b65942b4661741c469f047876f4cf4e23103ca7f','6f909927ced898c92b21d405a6374c1409bd3650','f32255f02c0873f1d56f503c117a3692f075a6f3']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=ofc8.699852ecde430b12"

   strings:
      $hex_string = { 759fd9d4879e4abb4db7a8557ab80b1cf02870d3b69bdad0e50fce2684d1184ff800105dae2a891373015827d725e33ad8d69d32988ca3c5f7d5c4dfbe1d8629 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
