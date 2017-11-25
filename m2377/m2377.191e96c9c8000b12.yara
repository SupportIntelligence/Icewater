
rule m2377_191e96c9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.191e96c9c8000b12"
     cluster="m2377.191e96c9c8000b12"
     cluster_size="6"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker script"
     md5_hashes="['317c17c48f34bf8fdbc685d0da275968','3c3c6c1cdd09f584756e0ac1f2944960','e8dcb156ba0e137a96359542e142da6b']"

   strings:
      $hex_string = { 4d6963726f736f66742e416c706861284f7061636974793d3029262333393b3b20206d617267696e2d6c6566743a202d353070783b207a2d696e6465783a2031 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
