
rule m26d4_51e435314aab1132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26d4.51e435314aab1132"
     cluster="m26d4.51e435314aab1132"
     cluster_size="20"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="mywebsearch mindspark webtoolbar"
     md5_hashes="['e3b85bc0cab69cb24972a22fe70a12b4d6a550e2','08c52194baa4852056e163318a02a73cd11574f6','12960b5ffc0042cea0d9490880fb32633f279420']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26d4.51e435314aab1132"

   strings:
      $hex_string = { b0040000200200000f387e83504f5055504d454e555f434c415353571500536b696e20312e302054797065204c696272617279571c0050736575646f20547261 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
