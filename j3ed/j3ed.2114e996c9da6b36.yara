
rule j3ed_2114e996c9da6b36
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3ed.2114e996c9da6b36"
     cluster="j3ed.2114e996c9da6b36"
     cluster_size="82"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171117"
     license = "RIL-1.0 [Rick's Internet License] "
     family="malicious proxy filerepmalware"
     md5_hashes="['009cc0c6bedbab75d05d5dabc19bb050','03e0d47b05a555f03c380b1e7f3b33ad','26c225482e1c5e1da7bf37a754cee8c6']"

   strings:
      $hex_string = { 1033d242d1e281c2b4f1c90103c22bd28d8215bdffdb0503930034b96054818d50890c248b0c2481e9f5ee0e1f518f0424505a8f0040c742047fda99b348836a }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
