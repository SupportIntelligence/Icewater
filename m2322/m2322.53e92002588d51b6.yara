
rule m2322_53e92002588d51b6
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2322.53e92002588d51b6"
     cluster="m2322.53e92002588d51b6"
     cluster_size="6"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['3bdc629c5b3bf9b4dbb986f6f665720c','3c704a320222711b2955ba52b4032c59','c5051c0c8dbe45109b027a370671ac2d']"

   strings:
      $hex_string = { a79a70928d12305debc594f662f9a13f3fe98f8aa8603fb3995e5930a5b645768bc0cb79455e444887cc3be14291e3c5de58465f20c1ab7f15433f4f01a6cc17 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
