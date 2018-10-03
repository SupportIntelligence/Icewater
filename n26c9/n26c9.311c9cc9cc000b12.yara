
rule n26c9_311c9cc9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26c9.311c9cc9cc000b12"
     cluster="n26c9.311c9cc9cc000b12"
     cluster_size="23"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="expiro malicious filerepmalware"
     md5_hashes="['3007a699380ed895a2d102fc68f3e56f11abbe24','2ffaa5bc99ad8eb350358421ddf646643834eaca','9cab3001db6f1f57bc8a64437a6a14ddcefc2f08']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26c9.311c9cc9cc000b12"

   strings:
      $hex_string = { 498bd8663bc275274885db7422488d0d89ca0000488bd3e8993800008bf885c078090fb70bff1542bfffff8bc7eb05b857000780488b5c24304883c4205fc3cc }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
