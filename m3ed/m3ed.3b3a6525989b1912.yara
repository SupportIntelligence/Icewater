
rule m3ed_3b3a6525989b1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.3b3a6525989b1912"
     cluster="m3ed.3b3a6525989b1912"
     cluster_size="7"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul bqjjnb"
     md5_hashes="['0735b2d117dfbcd51f68814430402f56','0b9584d2848a368df3555a60c37da4c6','dbe6dc7c59199e49071c67409265ce05']"

   strings:
      $hex_string = { 8a46018847018b45085e5fc9c353576a0233dbe8e4cfffff596a035f393de00801107e5d56a1d8f800108bf7c1e6028b040685c07441f6400c83740d50e8dc11 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
