import "hash"

rule k3e9_52969499c2200b14
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.52969499c2200b14"
     cluster="k3e9.52969499c2200b14"
     cluster_size="55"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171105"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['057aebc166b86f7e308f27dc3cd9b015','12991b5bafa296fdeb7dc6acd24e0ccb','5cee796854716eb1e9ba122a297b495f']"


   condition:
      
      filesize > 16384 and filesize < 65536
      and hash.md5(0,4096) == "00b8c10b0e6b00d1d92f1a0ed679391a"
}

