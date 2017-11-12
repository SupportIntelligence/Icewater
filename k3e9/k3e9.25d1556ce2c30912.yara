import "hash"

rule k3e9_25d1556ce2c30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.25d1556ce2c30912"
     cluster="k3e9.25d1556ce2c30912"
     cluster_size="17"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171105"
     license = "RIL-1.0 [Rick's Internet License] "
     family="parite pate pinfi"
     md5_hashes="['0ce0238ab6aef5d7ece3a18749eb33ca','212ca2dac01e6437096b5b4b11f51915','ffec234cb12582ae4cacdd45ba1edb7b']"


   condition:
      
      filesize > 262144 and filesize < 1048576
      and hash.md5(262144,65536) == "b8bcca7ac35f2c08b726dc2091b070d7"
}

