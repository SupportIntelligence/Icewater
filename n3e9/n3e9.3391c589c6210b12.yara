
rule n3e9_3391c589c6210b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.3391c589c6210b12"
     cluster="n3e9.3391c589c6210b12"
     cluster_size="29"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="razy malicious nymaim"
     md5_hashes="['02e1c888b5e78827c6978e7d1f43c748','12b1ac4d1325f1a310d10d196d5bc1dd','8f55d3245ada143a0f565e2c14489cc5']"

   strings:
      $hex_string = { 8832803b09419f0fd0aebd47b90a5bf97260a5f83fb2bbda313a45f1bfb1894858c4fbab0d630049e72e4098591ccdb4677654d715ace1f52bee64ea9205af2c }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
