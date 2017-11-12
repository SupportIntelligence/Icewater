
rule m3ed_6b122b25d5bb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.6b122b25d5bb1912"
     cluster="m3ed.6b122b25d5bb1912"
     cluster_size="274"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul bqjjnb"
     md5_hashes="['01f71085566d128ad298c8c970a56f24','045d43834b9ee585aebafba2c4766166','2a19f3cbcbd23066de628e4cc3c3aa7e']"

   strings:
      $hex_string = { 403bc672be8b4dfc5ee8b3a3ffffc9c3558bec83ec1ca1f481011053568b750833db3bf38945fc570f845401000033d233c039b0688a0110746583c030423df0 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
