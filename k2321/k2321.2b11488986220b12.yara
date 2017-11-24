
rule k2321_2b11488986220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2b11488986220b12"
     cluster="k2321.2b11488986220b12"
     cluster_size="6"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="brontok email pazetus"
     md5_hashes="['25490711573f8e921a3a994f91fafe53','334a09c427cc3cf65375a3f7436f2b89','dccee203eb52f280fcf81b470bc31b7e']"

   strings:
      $hex_string = { b4beb9bc02e6e8d234d50b5cdeeb1c8d5bdff4ab3efb4883b200512409a270b175e65962a1166b9fed534d3cc06af56d43e085457b29e29964e9a85ef1d7fa4e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
