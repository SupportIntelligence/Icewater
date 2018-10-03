
rule n26c9_33161ec1cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26c9.33161ec1cc000b32"
     cluster="n26c9.33161ec1cc000b32"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="expiro malicious allinone"
     md5_hashes="['2910271d4b6ddcf4952a0ba192d1b17e1f8fea05','39b3d1404a0939f5ebaeadf33e76389122070763','5b6afcdc8bacba881ec0985ab7562186e0250c19']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26c9.33161ec1cc000b32"

   strings:
      $hex_string = { 498bd8663bc275274885db7422488d0d89ca0000488bd3e8993800008bf885c078090fb70bff1542bfffff8bc7eb05b857000780488b5c24304883c4205fc3cc }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
