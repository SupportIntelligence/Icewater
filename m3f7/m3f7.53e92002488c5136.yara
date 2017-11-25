
rule m3f7_53e92002488c5136
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.53e92002488c5136"
     cluster="m3f7.53e92002488c5136"
     cluster_size="15"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['074f16872859b37b237e2af13ab3b0ba','13f688b179b47a569d1705feb1d5543d','d9daf47e0ac24ea2c32115f3d22fc5bf']"

   strings:
      $hex_string = { a79a70928d12305debc594f662f9a13f3fe98f8aa8603fb3995e5930a5b645768bc0cb79455e444887cc3be14291e3c5de58465f20c1ab7f15433f4f01a6cc17 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
