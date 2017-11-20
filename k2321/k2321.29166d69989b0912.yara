
rule k2321_29166d69989b0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.29166d69989b0912"
     cluster="k2321.29166d69989b0912"
     cluster_size="5"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171117"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba emotet zusy"
     md5_hashes="['1a7a9e8f5f648e2b85a9fb71cbb6552b','269b2b752be6a0e70cc820cdcae5a75c','b6c6c0be3b05866af7eecf992d563a67']"

   strings:
      $hex_string = { 729d4ca695cb7432b93f6a3664608944c2e588396c5c8c8d089f3261dcb6cd9b8e1c3a6869acbf73f3c6d3870f1eddbb7dffe6f54777efc09a7bb76f99ebea0e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
