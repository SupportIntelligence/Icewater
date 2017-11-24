
rule n3ed_4920524148814ad2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.4920524148814ad2"
     cluster="n3ed.4920524148814ad2"
     cluster_size="176"
     filetype = "PE32 executable (DLL) (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jacard malicious delf"
     md5_hashes="['03cce807669be792b79f22637d525173','03fe52338bdc9b415d0fe2acb341d4bc','54d49f9d237cc8a2879a5b0788c44b78']"

   strings:
      $hex_string = { ae377a1e3974e38a82d0602c85f008b5b3c7f7a50c173a61c931cadd4c62999746de653ef894e8132dc270dbc40d7ecbb9ed110495bfe61033a66f005436d2be }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
