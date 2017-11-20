
rule k3f9_319d240d9ec30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f9.319d240d9ec30912"
     cluster="k3f9.319d240d9ec30912"
     cluster_size="40"
     filetype = "MS-DOS executable"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="genpack selfdel generickdz"
     md5_hashes="['14e4a74f3aa1d8a8e3f0a740af78c056','2ef87b406f5558cf909f3142067eb17d','bb4c20fd2a38cf93cec090e731739070']"

   strings:
      $hex_string = { 06092fb4c2114a0486ab5d10ce209a0fda230090f0ebdf2be4d1019164c777d55bc10b416064d70f6189c9be4fd8493142361adc3332212744cb157aea7e951d }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
