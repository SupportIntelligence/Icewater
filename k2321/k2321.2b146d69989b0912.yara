
rule k2321_2b146d69989b0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2b146d69989b0912"
     cluster="k2321.2b146d69989b0912"
     cluster_size="6"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba zusy emotet"
     md5_hashes="['0778826bb11d661ff0ee967c7b87d9c7','4c850134f1763abfc44582881bf1a890','bb8d09c6faaaa9e562d019a4ea84c9d3']"

   strings:
      $hex_string = { 729d4ca695cb7432b93f6a3664608944c2e588396c5c8c8d089f3261dcb6cd9b8e1c3a6869acbf73f3c6d3870f1eddbb7dffe6f54777efc09a7bb76f99ebea0e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
