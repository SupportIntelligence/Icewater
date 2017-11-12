
rule m3f9_0b11a8228ba90912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f9.0b11a8228ba90912"
     cluster="m3f9.0b11a8228ba90912"
     cluster_size="303"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="firseria bundler firser"
     md5_hashes="['0165794f97748ad20dec8c05c3b22d23','01a5e04faa3914e038b2d3997bb90492','11454b1c0362195af1dd9c2befb26a84']"

   strings:
      $hex_string = { c5bb333ad9df7d2f7b841b5f27f5d6484cde2b765c6db3009eaa9ae9416a0dc7be5063a993f90b2235ee7ffeb37421bae049ec06a5f0dbc6ce126273d710da6f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
