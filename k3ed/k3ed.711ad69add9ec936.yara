
rule k3ed_711ad69add9ec936
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ed.711ad69add9ec936"
     cluster="k3ed.711ad69add9ec936"
     cluster_size="124"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="onlinegames gamethief enterak"
     md5_hashes="['002b88be8c1f359903124fa43b1639c9','061c903b76118ff79c589a120addaf54','2bbc24623d4b1767aad2de2d88bed436']"

   strings:
      $hex_string = { 0c6cea037e1ec98b15042bce40aa377403b9aad39dadc7d33eb1309c253d0ccdecec68411018d69d5ffb73a8a12fa9f85250559caf979cd154e53eb85e4dbd25 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
