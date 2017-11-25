
rule m3f7_52db200084b14c9a
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.52db200084b14c9a"
     cluster="m3f7.52db200084b14c9a"
     cluster_size="34"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['006e2a193cb29d013ba9d34e61a6c805','09764d57aa41048271eb561f49d024f9','8e94cfcc08d164a4b178da25b7a5f1dc']"

   strings:
      $hex_string = { 212d2d726fce56773f3edf65793ad86db2c7b1fee0f9f6d31bef8c49c9884af27cfcc89ebcce8d8f8447c1a02a043cabf1363fc35a737c8d8793b83d1fadb775 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
