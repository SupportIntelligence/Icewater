
rule m2321_0aa354423543485a
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.0aa354423543485a"
     cluster="m2321.0aa354423543485a"
     cluster_size="13"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jadtre qvod viking"
     md5_hashes="['28b3a7e34706dac7bf03b5b3fa1bcc6d','3806a2ec263b9302ab0dd014d798d332','f4d45402e6b76e1c5f21349349748d89']"

   strings:
      $hex_string = { 554533e10f2902205456baa2acf2f00727d32c4b6b665a40658579b17797b9f543627ba51576633c41b4349309c7dea00c7f64ea92b68e96237319cea62124eb }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
