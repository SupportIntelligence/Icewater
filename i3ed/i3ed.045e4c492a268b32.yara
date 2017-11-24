
rule i3ed_045e4c492a268b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i3ed.045e4c492a268b32"
     cluster="i3ed.045e4c492a268b32"
     cluster_size="51"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="gamarue debris generickdz"
     md5_hashes="['0d12fa1634d29d24552aabaed33b750d','1488ebe66ad74e61b6eceec48d5c489e','ad53279d91daf3d20e5431c60813e938']"

   strings:
      $hex_string = { 104084d275f92bc14885c07e130fbe0c378a143088143747880c30483bf87ced5fc3568bf0e8cdffffffeb03fe0e46803e0075f85ec3558bec83ec0c535657b8 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
