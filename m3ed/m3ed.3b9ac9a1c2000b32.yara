
rule m3ed_3b9ac9a1c2000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.3b9ac9a1c2000b32"
     cluster="m3ed.3b9ac9a1c2000b32"
     cluster_size="323"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit cosmu nimnul"
     md5_hashes="['01b55378421d73a4c77643917f7d7571','02d36c940dd18446476d36fd0d02146f','296f8653bb071e416a80cdb869e58e4d']"

   strings:
      $hex_string = { 397de07c9333db8bf36bf6280335a03801108b0683f8ff740b83f8fe7406804e0480eb72c646048185db75056af658eb0a8bc348f7d81bc083c0f550ff1530e1 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
