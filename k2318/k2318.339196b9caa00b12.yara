
rule k2318_339196b9caa00b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.339196b9caa00b12"
     cluster="k2318.339196b9caa00b12"
     cluster_size="102"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['76fa95e41f181643772afe8b0db1fc1e11b92f0b','624cf177f8388ca7bf0cc3d6575352c8c7959b61','05fa4348b8ba4f6c60e0e540c1af79945fae2bd7']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.339196b9caa00b12"

   strings:
      $hex_string = { 74642077696474683d223130302522206865696768743d2231342220636c6173733d22696e666f426f7848656164696e67223ed0e0e7e4e5ebfb3c2f74643e0a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
