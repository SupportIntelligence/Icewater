import "hash"

rule k3e9_2b4666998c7c6d96
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2b4666998c7c6d96"
     cluster="k3e9.2b4666998c7c6d96"
     cluster_size="28497"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171105"
     license = "RIL-1.0 [Rick's Internet License] "
     family="brontok eyvjjib fmmfr"
     md5_hashes="['00038063aa4f5fbe4196c79b4bcd8b13','000d70f77f56d64c98097b0781fef540','007058d8fca3bff4bd8c78b61c73e2ce']"


   condition:
      
      filesize > 65536 and filesize < 262144
      and hash.md5(16384,16384) == "c48b22962220f1b8cd68a4044b8e1498"
}

