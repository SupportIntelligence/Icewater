
rule k3ec_2911c80986220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ec.2911c80986220b12"
     cluster="k3ec.2911c80986220b12"
     cluster_size="5"
     filetype = "PE32 executable (console) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="brontok email pazetus"
     md5_hashes="['628ee7eed7cb35dfa1fccd67fc83b64d','82191b1c248ad0013f780982463a8027','cd9c732e54cf34d2c6e48bfec07344e7']"

   strings:
      $hex_string = { b4beb9bc02e6e8d234d50b5cdeeb1c8d5bdff4ab3efb4883b200512409a270b175e65962a1166b9fed534d3cc06af56d43e085457b29e29964e9a85ef1d7fa4e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
