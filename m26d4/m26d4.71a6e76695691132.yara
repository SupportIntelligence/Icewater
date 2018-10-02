
rule m26d4_71a6e76695691132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26d4.71a6e76695691132"
     cluster="m26d4.71a6e76695691132"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="mywebsearch webtoolbar malicious"
     md5_hashes="['e76055225753b2d4ff61afa81eec53f9cd2e3e86','ccf9d427723ee8fec88da7943d4702b97cee9c89','d96c57411a4b8233be94aa40a42128bc5a1b59e0']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26d4.71a6e76695691132"

   strings:
      $hex_string = { 040200000f387e83504f5055504d454e555f434c415353571500536b696e20312e302054797065204c696272617279571c0050736575646f205472616e737061 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
