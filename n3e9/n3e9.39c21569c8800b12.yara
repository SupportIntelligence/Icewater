
rule n3e9_39c21569c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.39c21569c8800b12"
     cluster="n3e9.39c21569c8800b12"
     cluster_size="49"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zusy trojandropper backdoor"
     md5_hashes="['0b32ed282fc17b7cb675bda6feb0ef35','1c03ff1a0808d259b7f9ff2414ccd613','a26139a8fed08d95900ff1fa28e92f9c']"

   strings:
      $hex_string = { 3f4c3f5e3f703f823f943fa63fe03f000000c00100440000005d32c632d732fd340e352e3557356b357f35eb352736ac36ed361037be38fb38b539be39003a09 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
