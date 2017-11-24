
rule k2321_23146d6d989b0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.23146d6d989b0912"
     cluster="k2321.23146d6d989b0912"
     cluster_size="5"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="emotet tinba vbkrypt"
     md5_hashes="['50b8fa9489a158f52da500269cd8bf79','7e9aa213222740cdc522c61e75e60d96','abec85cc9b8de9c994edf4f78591bee9']"

   strings:
      $hex_string = { 729d4ca695cb7432b93f6a3664608944c2e588396c5c8c8d089f3261dcb6cd9b8e1c3a6869acbf73f3c6d3870f1eddbb7dffe6f54777efc09a7bb76f99ebea0e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
