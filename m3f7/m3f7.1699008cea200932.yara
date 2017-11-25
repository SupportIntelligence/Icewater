
rule m3f7_1699008cea200932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.1699008cea200932"
     cluster="m3f7.1699008cea200932"
     cluster_size="13"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['0dc36bb603c1c13a5d2ab7b0be9e534c','0fb4744eade6454effc7c3be92a0ad24','f8e3fc7082ee686164f0e38597d5b747']"

   strings:
      $hex_string = { 35393033423438373136433034393833363241383245434437454631343246444334414245334346353138454538333937353242453035324642343141363144 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
