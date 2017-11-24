
rule k3e9_6ad2d79c16996d96
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6ad2d79c16996d96"
     cluster="k3e9.6ad2d79c16996d96"
     cluster_size="788"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="outbrowse bundler unwanted"
     md5_hashes="['0106c2aa4c2bd9e0d0fb08c04c3660c7','02fcd030b80041fbd215e7f2c4f43893','11299d7cbf864f205ea0af30f057feaf']"

   strings:
      $hex_string = { 027c77e3d4d1279a979c2a0df975e2c7e0b7bbf647f194b6c4cae52b50765999a98ab2c21513877961f26b165cdbaab1a2f0d90983d33f31b5cf537fdd50fbb3 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
