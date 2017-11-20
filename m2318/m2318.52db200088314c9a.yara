
rule m2318_52db200088314c9a
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2318.52db200088314c9a"
     cluster="m2318.52db200088314c9a"
     cluster_size="5"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['59de65b7677d2965f6abc6a9da04e15f','5a75de50aa4accbbe39c45e71ef7c29b','ff48d2705d7ae2acec4778a52eff3917']"

   strings:
      $hex_string = { 212d2d726fce56773f3edf65793ad86db2c7b1fee0f9f6d31bef8c49c9884af27cfcc89ebcce8d8f8447c1a02a043cabf1363fc35a737c8d8793b83d1fadb775 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
