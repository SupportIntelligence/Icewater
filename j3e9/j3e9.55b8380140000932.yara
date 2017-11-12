
rule j3e9_55b8380140000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e9.55b8380140000932"
     cluster="j3e9.55b8380140000932"
     cluster_size="457"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hematite hworld infector"
     md5_hashes="['0072ce5e80f367a2f04364fe2a9ac96a','00dd9a1ff4d004b193792dd8c495734f','0ad66274a92d3af74e0ada43719174d0']"

   strings:
      $hex_string = { 050105e800000000010101ac01010150010101560101015701010151230405b91df301000833c981c11df301000bb9d3f2000081c14a0001000bb902fa060081 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
