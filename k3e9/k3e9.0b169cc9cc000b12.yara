
rule k3e9_0b169cc9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.0b169cc9cc000b12"
     cluster="k3e9.0b169cc9cc000b12"
     cluster_size="5"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="rincux ddos stormattack"
     md5_hashes="['2ceebc1719d317b589499b7ebc57a992','34e0d2f4401c4f732f52a68bd009733c','e82067eefc7b80fce9a71b231861b37d']"

   strings:
      $hex_string = { bdcc42812a8c34ae8b9283051449ec9ff08f12940ab328bed84c49880762ca2497298ec40e21236e4fc6fbe9e8ea93ce448a3d156f1fd93f844709de48c5a304 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
