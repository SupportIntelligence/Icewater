
rule m3f0_699f9699c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f0.699f9699c2200b12"
     cluster="m3f0.699f9699c2200b12"
     cluster_size="43"
     filetype = "PE32 executable (GUI) Intel 80386 (stripped to external PDB)"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="gepys kryptik razy"
     md5_hashes="['0e9df163bdeec16834d61081cd3457d1','1016183d4fa6c15410600bbc832a4f3d','545ef5b62181b9f987107b16ae322345']"

   strings:
      $hex_string = { 9a3a4abffbcaafc5a16ee8b65f2e547ce0290b76459ee12fdd2352064468eb2ded824e9960bb964c6bff4157177495bc4c1648f9b59db02c814fd51885bdd777 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
