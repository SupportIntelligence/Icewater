
rule m3f7_52db200084354c9a
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.52db200084354c9a"
     cluster="m3f7.52db200084354c9a"
     cluster_size="6"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['05ff7cafdc35c5c73c8a1b80af42e347','33bdb8d3067badff0781a3ad9da46911','b6383a2366bd5e73005edd8e04992321']"

   strings:
      $hex_string = { 212d2d726fce56773f3edf65793ad86db2c7b1fee0f9f6d31bef8c49c9884af27cfcc89ebcce8d8f8447c1a02a043cabf1363fc35a737c8d8793b83d1fadb775 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
