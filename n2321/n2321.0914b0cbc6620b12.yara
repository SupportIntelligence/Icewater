
rule n2321_0914b0cbc6620b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2321.0914b0cbc6620b12"
     cluster="n2321.0914b0cbc6620b12"
     cluster_size="17"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nymaim razy bbyw"
     md5_hashes="['012a246c0d3436c57bdc6f993ffce906','0d5aa75553c76ba387ccab37aa509fa9','fde19a32d35064a5a55475febf55d72c']"

   strings:
      $hex_string = { 763951dc0a5bcca6eb5d1a212e61794b85103e9e75b0d46874a3508a70ea14e800f8b7bae4c0b97736c311db8dd70e0ca5e3d57d1c82caff7c1869499c4e66f0 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
