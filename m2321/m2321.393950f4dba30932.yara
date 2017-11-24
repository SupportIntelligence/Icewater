
rule m2321_393950f4dba30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.393950f4dba30932"
     cluster="m2321.393950f4dba30932"
     cluster_size="5"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="cripack yakes tinba"
     md5_hashes="['0cc5f3109d41ed3cb32dd7a2cea046a9','6d694f20ecef2deb3ac891261b466f92','b2e6ab9ab6d1405127c59fe0dc70dd4e']"

   strings:
      $hex_string = { 3082c076d8484b54bc52704af1b2403ca17ff46b597e8c0d223d2ed1a6a9149e6e20c5c49decac12c72e7cbbeab45c1f167425af989f970ebdf2299285cca315 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
