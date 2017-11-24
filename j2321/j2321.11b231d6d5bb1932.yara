
rule j2321_11b231d6d5bb1932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2321.11b231d6d5bb1932"
     cluster="j2321.11b231d6d5bb1932"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="upatre trojandownloader waski"
     md5_hashes="['12ed0990f21709e2182dc1a1065b97ab','416fa103ff272922e23a381fb97190ac','b3ef23d8302e48efa7f329cd43e1385d']"

   strings:
      $hex_string = { 9bb0677e7279939e78d5db5a3d0f34c9302668ef914bc21f5d8812b9dbd7dec18b068ddfd2ab4db3026e77cea90405892c855e9c1e45af18f9bab8f88cf6fd5b }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
