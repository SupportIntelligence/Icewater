
rule m26d4_51e435314aab5132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26d4.51e435314aab5132"
     cluster="m26d4.51e435314aab5132"
     cluster_size="8"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="mywebsearch mindspark webtoolbar"
     md5_hashes="['95479c9d92dfb12c1338be6fae432d8e7b693544','efd1b9232638f055dbe6312041dd40dd749018aa','743d6e6b146a240fb5fe355833b769b5f2de7e38']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26d4.51e435314aab5132"

   strings:
      $hex_string = { b0040000200200000f387e83504f5055504d454e555f434c415353571500536b696e20312e302054797065204c696272617279571c0050736575646f20547261 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
