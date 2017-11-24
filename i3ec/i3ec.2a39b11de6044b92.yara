
rule i3ec_2a39b11de6044b92
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i3ec.2a39b11de6044b92"
     cluster="i3ec.2a39b11de6044b92"
     cluster_size="83"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fileinfector malicious ccmw"
     md5_hashes="['01f2d546268e9451109dea3ed28ac687','0291a4727b7b3c344716f83a39e34357','1b33aff7b4284d881c9060162462e4ed']"

   strings:
      $hex_string = { 0233d2022bd2020102f7e30602022bf8048bd82bfb06020285ff048bdf85db1602087f0681c7ffffff7f0e7f0c81c77856341281c787a9cb6d030103897d0005 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
