
rule i3ed_045e4c492a2c8b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i3ed.045e4c492a2c8b32"
     cluster="i3ed.045e4c492a2c8b32"
     cluster_size="43"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="gamarue debris generickdz"
     md5_hashes="['0557fd5f562acbe901195384a35da173','0e68510f2c9eab52ae9a64c0e4a0998e','ba04680d5ab179e27e8280506b0bacc0']"

   strings:
      $hex_string = { 104084d275f92bc14885c07e130fbe0c378a143088143747880c30483bf87ced5fc3568bf0e8cdffffffeb03fe0e46803e0075f85ec3558bec83ec0c535657b8 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
