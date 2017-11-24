
rule m2318_613d684dd8bf4932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2318.613d684dd8bf4932"
     cluster="m2318.613d684dd8bf4932"
     cluster_size="20"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['0499bdd009ca02733af839e086bc8950','0db647c1fd6d838f8fd0dba9ed1166cb','c657f3bba116d5e983e05950a6715be0']"

   strings:
      $hex_string = { 35393033423438373136433034393833363241383245434437454631343246444334414245334346353138454538333937353242453035324642343141363144 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
