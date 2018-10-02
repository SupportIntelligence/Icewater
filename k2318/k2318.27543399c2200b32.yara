
rule k2318_27543399c2200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.27543399c2200b32"
     cluster="k2318.27543399c2200b32"
     cluster_size="9025"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['f0def33899fcfd4c628075b3e6fd564639e099fb','0c7c5470681311d538fcd77a838b8591ece35e19','5e0977ba86b987e8e9ecf00afb11a99188403202']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.27543399c2200b32"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
