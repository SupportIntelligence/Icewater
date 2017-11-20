
rule j2321_32126d6284992937
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2321.32126d6284992937"
     cluster="j2321.32126d6284992937"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="small generickd upatre"
     md5_hashes="['ab450594ef01e40a6dd8c5a38954b729','ac32871630f64fb02522746f35396736','ffcd7d91304ff255d4b9e9d3cd0b63ee']"

   strings:
      $hex_string = { 06117aaa437d48a4ae909558678ef53523c9e2bc37273854e8723d51742cca14dc3bf039f85707871a13eef970df2b178d485cd7fe66d04c6e0cea306e9c20b7 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
