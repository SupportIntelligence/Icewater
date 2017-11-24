
rule k3ec_0319cc22d3a30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ec.0319cc22d3a30932"
     cluster="k3ec.0319cc22d3a30932"
     cluster_size="4"
     filetype = "PE32 executable (console) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hupigon backdoor razy"
     md5_hashes="['25dfeae5661d098ebb8d12f60e4c79f3','a757162d295ddbb14bd09ffefe883ac9','f608e24c3f18081f27462fe5fde49529']"

   strings:
      $hex_string = { f7c1249d0a596f9e376b3c51331a4afc34a2c55f3df376a8d6429992b7a05a9f4362f595b329786977e2a1b844c72fd9e1e9d51ede8efbcff0790bbda3352d13 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
