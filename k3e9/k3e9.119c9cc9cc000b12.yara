
rule k3e9_119c9cc9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.119c9cc9cc000b12"
     cluster="k3e9.119c9cc9cc000b12"
     cluster_size="68"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vilsel aems riskware"
     md5_hashes="['00bf68a4edcfe93dafc63d134d7d13b6','02fbb223dfca4d37e7bd522d3dc78af7','3d8fe9e913e31063a3ac90c715a28b3b']"

   strings:
      $hex_string = { 53ab41304b0ebb5e2b762868c44d7a1bbd3c22f38c5abeaff19eb98b49938852f40abeb04c45ea8659c1049b446a1aa6bee0944851cc79b6dc4a9da35485953a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
